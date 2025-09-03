from . import pyparallax_shim

PAR_CREATE_DB = 4
PAR_DONOT_CREATE_DB = 5

def format(device_name: str, max_regions: int) -> str | None:
    print("[pyParallax] Calling par_format")
    return pyparallax_shim.format(device_name, max_regions)

def open(volume_name: str, db_name: str, create_flag: int):
    print("[pyParallax] Calling par_open") 
    return pyparallax_shim.open(volume_name, db_name, create_flag)

def put(handle, key: bytes, value: bytes) -> None:
    print("[pyParallax] Calling par_put") 
    return pyparallax_shim.put(handle,key,value)

def get(handle, key: str | bytes) -> bytes | None:
    print("[pyParallax] Calling par_get") 
    return pyparallax_shim.get(handle, key)

def close(handle) -> None:
    print("[pyParallax] Calling par_close") 
    return pyparallax_shim.close(handle)

