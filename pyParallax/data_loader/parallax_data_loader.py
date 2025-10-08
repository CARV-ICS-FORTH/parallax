from time import time
import logging
import math
import pickle
import torch
from torch.utils.data import Dataset, DataLoader, RandomSampler, SequentialSampler
from torch.utils.data.sampler import Sampler
import numpy as np

from dlio_benchmark.common.constants import MODULE_DATA_LOADER
from dlio_benchmark.common.enumerations import Shuffle, DatasetType, DataLoaderType
from dlio_benchmark.data_loader.base_data_loader import BaseDataLoader
from dlio_benchmark.reader.reader_factory import ReaderFactory
from dlio_benchmark.utils.utility import utcnow, DLIOMPI
from dlio_benchmark.utils.config import ConfigArguments
from dlio_benchmark.utils.utility import Profile

# Import your Parallax library
import pyParallax as py_par

dlp = Profile(MODULE_DATA_LOADER)

class dlio_sampler(Sampler):
    def __init__(self, rank, size, num_samples, epochs):
        self.size = size
        self.rank = rank
        self.num_samples = num_samples
        self.epochs = epochs
        samples_per_proc = int(math.ceil(num_samples/size)) 
        start_sample = self.rank * samples_per_proc
        end_sample = (self.rank + 1) * samples_per_proc - 1
        if end_sample > num_samples - 1:
            end_sample = num_samples - 1
        self.indices = list(range(start_sample, end_sample + 1))

    def __len__(self):
        return len(self.indices)

    def __iter__(self):
        for sample in self.indices:
            yield sample

class ParallaxDataset(Dataset):
    """
    A PyTorch Dataset class for reading samples from Parallax.
    """

    @dlp.log_init
    def __init__(self, format_type, dataset_type, epoch, num_samples, num_workers, batch_size, kv_path):
        self.format_type = format_type
        self.dataset_type = dataset_type
        self.epoch_number = epoch
        self.num_samples = num_samples
        self.batch_size = batch_size
        self.kv_path = kv_path
        self.num_images_read = 0
        
        # DLIO configuration and logging setup
        args = ConfigArguments.get_instance()
        self.serial_args = pickle.dumps(args)
        self.logger = args.logger
        self.dlp_logger = None
        self.handle = None

        if num_workers == 0:
            self.worker_init(-1)

    @dlp.log
    def worker_init(self, worker_id):
        """Initialize worker process for KV store connection and logging."""
        pickle.loads(self.serial_args)
        _args = ConfigArguments.get_instance()
        _args.configure_dlio_logging(is_child=True)
        self.dlp_logger = _args.configure_dftracer(is_child=True, use_pid=True)
        
        self.logger.debug(f"{utcnow()} Parallax worker initialized {worker_id} for dataset {self.dataset_type}")
        
        self.handle = py_par.open(self.kv_path, "mlperf_db", py_par.opts.PAR_CREATE_DB)
        self.logger.debug(f"{utcnow()} Worker {worker_id} connected to KV store at {self.kv_path}")

    def __del__(self):
        """Cleanup resources."""
        if self.dlp_logger:
            self.dlp_logger.finalize()
        if self.handle:
            py_par.close(self.handle)

    @dlp.log
    def __len__(self):
        return self.num_samples

    @dlp.log
    def __getitem__(self, index):
        self.num_images_read += 1
        step = int(math.ceil(self.num_images_read / self.batch_size))
        
        self.logger.debug(f"{utcnow()} Reading sample {index} from KV store")
        dlp.update(step=step)
        
        # Generate key and fetch value from KV store
        key = str(index).encode('utf-8')
        serialized_value = py_par.get(self.handle, key)
        
        if serialized_value is None:
            raise ValueError(f"Key {key} not found in KV store")
        
        sample_data = pickle.loads(serialized_value)
        
        return sample_data

class ParallaxDataLoader(BaseDataLoader):
    """
    DataLoader implementation for Parallax KV store integration with DLIO.
    """

    @dlp.log_init
    def __init__(self, format_type, dataset_type, epoch_number):
        super().__init__(format_type, dataset_type, epoch_number, DataLoaderType.PARALLAX)

    @dlp.log
    def read(self):
        """Initialize the dataset and data loader."""
        # Create dataset instance
        dataset = ParallaxDataset(
            format_type=self.format_type,
            dataset_type=self.dataset_type,
            epoch=self.epoch_number,
            num_samples=self.num_samples,
            num_workers=self._args.read_threads,
            batch_size=self.batch_size,
            kv_path=self._args.data_folder  
        )
        
        # Create distributed sampler
        sampler = dlio_sampler(
            rank=DLIOMPI.get_instance().rank(),
            size=DLIOMPI.get_instance().size(),
            num_samples=self.num_samples,
            epochs=self._args.epochs
        )
        
        # Calculate prefetch factor
        if self._args.read_threads >= 1:
            prefetch_factor = math.ceil(self._args.prefetch_size / self._args.read_threads)
        else:
            prefetch_factor = self._args.prefetch_size
        
        if prefetch_factor > 0:
            if self._args.my_rank == 0:
                self.logger.debug(
                    f"{utcnow()} Prefetch size is {self._args.prefetch_size}; prefetch factor of {prefetch_factor} will be set to Torch DataLoader.")
        else:
            prefetch_factor = 2
            if self._args.my_rank == 0:
                self.logger.debug(
                    f"{utcnow()} Prefetch size is 0; a default prefetch factor of 2 will be set to Torch DataLoader.")
        
        # Configure DataLoader kwargs
        if self._args.read_threads == 0:
            kwargs = {}
        else:
            kwargs = {
                'multiprocessing_context': self._args.multiprocessing_context,
                'prefetch_factor': prefetch_factor,
                'persistent_workers': True
            }
        
        # Handle version-specific quirks
        if torch.__version__ == '1.3.1':
            if 'prefetch_factor' in kwargs:
                del kwargs['prefetch_factor']
            if 'persistent_workers' in kwargs:
                del kwargs['persistent_workers']
        
        self.logger.debug(f"{utcnow()} Setting up Parallax DataLoader with {self._args.read_threads} workers")
        
        # Create the PyTorch DataLoader
        self._dataset = DataLoader(
            dataset,
            batch_size=self.batch_size,
            sampler=sampler,
            num_workers=self._args.read_threads,
            pin_memory=self._args.pin_memory,
            drop_last=True,
            worker_init_fn=dataset.worker_init,
            **kwargs
        )
        
        self.logger.debug(f"{utcnow()} Rank {self._args.my_rank} will read {len(self._dataset) * self.batch_size} samples")

    @dlp.log
    def next(self):
        """Iterate through batches in the dataset."""
        super().next()
        total = self._args.training_steps if self.dataset_type is DatasetType.TRAIN else self._args.eval_steps
        self.logger.debug(f"{utcnow()} Rank {self._args.my_rank} should read {total} batches")
        
        step = 1
        for batch in dlp.iter(self._dataset):
            dlp.update(step=step)
            step += 1
            yield batch
        
        self.epoch_number += 1
        dlp.update(epoch=self.epoch_number)

    @dlp.log
    def finalize(self):
        """Cleanup resources."""
        pass
