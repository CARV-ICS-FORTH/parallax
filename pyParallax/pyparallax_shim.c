#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdio.h>
#include "../lib/include/parallax/parallax.h"
#include "../lib/include/parallax/structures.h"

static PyObject *py_par_format(PyObject *self, PyObject *args){
	(void)self;

  const char *device_name;
	unsigned int max_regions;

	if (!PyArg_ParseTuple(args, "sI", &device_name, &max_regions)){
    return NULL; 
  }

	char *result = par_format((char*)device_name, max_regions);
	if(result == NULL){
		Py_RETURN_NONE;
	}

	return PyUnicode_FromString(result);

}

static PyObject *py_par_open(PyObject *self, PyObject *args){	
	(void)self;

  const char *volume_name;
	const char *db_name;
  int create_flag;
	const char *error_message = NULL;

	if (!PyArg_ParseTuple(args, "ssi", &volume_name, &db_name, &create_flag)) {
    return NULL; 
  }	

	par_db_options db_options = {
		.volume_name = (char*)volume_name,
		.db_name = db_name,
		.create_flag = create_flag,
		.options = par_get_default_options()
	};

	par_handle handle = par_open(&db_options, &error_message);

  if (handle == NULL) {    
		return NULL;
  }

	return PyCapsule_New(handle, "par_handle", NULL); 
}

static PyObject *py_par_get(PyObject *self, PyObject *args){
	(void)self;

  PyObject *capsule;
	const char *key_buf;
	Py_ssize_t key_len;
	const char *error_message = NULL;

	if (!PyArg_ParseTuple(args, "Os#", &capsule, &key_buf, &key_len)) {
    return NULL;
  }

	if (!PyCapsule_IsValid(capsule, "par_handle")) {
    PyErr_SetString(PyExc_TypeError, "Invalid handle capsule");
    return NULL;
  }

	par_handle handle = (par_handle)PyCapsule_GetPointer(capsule, "par_handle");

	struct par_key key = {
    .data = key_buf,
    .size = (uint32_t)key_len 
  };

	struct par_value value = {
    .val_buffer = NULL,
    .val_buffer_size = 0,
    .val_size = 0
  };

	par_get(handle, &key, &value, &error_message);

	if (error_message != NULL) {
    PyErr_SetString(PyExc_RuntimeError, error_message);
    return NULL;
  }

	if (value.val_size <= 0 ||  value.val_buffer == NULL) {
    Py_RETURN_NONE;
	}

  return PyBytes_FromStringAndSize(value.val_buffer, value.val_size);

}

static PyObject *py_par_put(PyObject *self, PyObject *args){
  (void)self;

  PyObject *capsule;
	const char *key_buf;
	Py_ssize_t key_len;
	const char *val_buf;
	Py_ssize_t val_len;
	const char *error_message = NULL;

	if (!PyArg_ParseTuple(args, "Oy#y#", &capsule, &key_buf, &key_len, &val_buf, &val_len)){
    return NULL;
	}
	
	if (!PyCapsule_IsValid(capsule, "par_handle")) {
    PyErr_SetString(PyExc_TypeError, "Invalid handle capsule");
    return NULL;
  }

	par_handle handle = (par_handle)PyCapsule_GetPointer(capsule, "par_handle");

	struct par_key k = {
		.data = key_buf,
		.size = (uint32_t)key_len
	};

	struct par_value v = {
		.val_size = (uint32_t)val_len,
		.val_buffer_size = (uint32_t)val_len,
		.val_buffer = (char*)val_buf
	};

	struct par_key_value kv = {
		.k = k,
		.v = v
	};

	struct par_put_metadata meta = par_put(handle, &kv, &error_message);
  (void)meta;

  if(error_message != NULL){
		PyErr_SetString(PyExc_RuntimeError, error_message);
    return NULL;
	}	

	Py_RETURN_NONE;
}


static PyObject *py_par_close(PyObject *self, PyObject *args){
  (void)self;

  PyObject *capsule;	
	const char *error_message = NULL;

	if (!PyArg_ParseTuple(args, "O", &capsule)) {
    return NULL;
  }

	if (!PyCapsule_IsValid(capsule, "par_handle")) {
    PyErr_SetString(PyExc_TypeError, "Invalid handle capsule");
    return NULL;
  }

	par_handle handle = (par_handle)PyCapsule_GetPointer(capsule, "par_handle");

	error_message = par_close(handle);

	if (error_message != NULL) {
    PyErr_SetString(PyExc_RuntimeError, error_message);
    return NULL;
  }

	Py_RETURN_NONE;
}

static PyMethodDef PyParallaxMethods[] = {
	{"format", py_par_format, METH_VARARGS, "Format a Parallax device"},
	{"open", py_par_open, METH_VARARGS, "Open Parallax DB"},
	{"get", py_par_get, METH_VARARGS, "Get Value"},
	{"put", py_par_put, METH_VARARGS, "Put Value"},
	{"close", py_par_close, METH_VARARGS, "Close parallax DB"},
	{NULL, NULL, 0, NULL}
};

static struct PyModuleDef pyparallaxmodule = {
	PyModuleDef_HEAD_INIT,
	"pyparallax_shim",
	"Python binding interface for Parallax",
	-1,
	PyParallaxMethods,
  NULL,
  NULL,
  NULL,
  NULL
};

PyMODINIT_FUNC PyInit_pyparallax_shim(void){
	return PyModule_Create(&pyparallaxmodule);
}

