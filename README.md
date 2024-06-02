# Parallax
Parallax is an LSM-based persistent key-value store designed for flash storage devices (SSDs, NVMe). Parallax reduces I/O amplification and increases CPU efficiency using the following mechanism. It categorizes key-value (KV) pairs into three size-based categories: Small, Medium, and Large. Then it applies a different policy for each category. It stores Small KV pairs inside the LSM levels (as RocksDB). It always performs key-value separation for KV pairs (as BlobDB), writing them in a value log, and it uses a garbage collection (GC) mechanism for the value log. For medium KV pairs, it uses a hybrid policy: It performs KV separation up to the semi-last levels and then stores them in place to bulk-free space without using GC.

<!---![Parallax](https://i.imgur.com/7XYSGwW.jpg)]-->

## Building Parallax

If you want to use Parallax check the [Build](docs/Build.md) guide.




## Acknowledgements
If you want to cite us or find more details in the paper:
```
Giorgos Xanthakis, Giorgos Saloustros, Nikos Batsaras, Anastasios Papagiannis, and Angelos Bilas. 2021. Parallax: Hybrid Key-Value Placement in LSM-based Key-Value Stores. In Proceedings of the ACM Symposium on Cloud Computing (SoCC '21). Association for Computing Machinery, New York, NY, USA, 305–318.
DOI:https://doi.org/10.1145/3472883.3487012
```

We thankfully acknowledge the support of the European Commission under the Horizon 2020 Framework Programme for Research and Innovation through the projects EVOLVE (Grant Agreement ID: 825061). This work is (also) partly supported by project EUPEX, which has received funding from the European High-Performance Computing Joint Undertaking (JU) under grant agreement No 101033975. The JU receives support from the European Union's Horizon 2020 re-search and innovation programme and France, Germany, Italy, Greece, United Kingdom, Czech Republic, Croatia.
