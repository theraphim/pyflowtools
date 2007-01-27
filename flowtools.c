/* $Header: /home/robin/repository/netflow/flowtools.c,v 1.9 2002/05/21 21:53:02 robin Exp $ */

#include <Python.h>
#include <fcntl.h>
#include <stddef.h>
#include <arpa/inet.h>

#define HAVE_STRSEP 1
#include <ftlib.h>

typedef struct {
  PyObject_HEAD

  int fd;

  struct ftio io;
  int ftio_init_complete;

  struct fts3rec_offsets offsets;
  u_int64 xfield;

} FlowSetObject;

typedef struct {
    PyObject_HEAD
    char *record;
    struct fts3rec_offsets fo;
    FlowSetObject *set;
} FlowObject;

/* Define flow attributes */

enum RecordAttrType {
    RF_ADDR, RF_UINT32, RF_UINT16, RF_UINT8, RF_TIME
};

struct RecordAttrDef {
  enum RecordAttrType type;
  u_int64 xfield;
  int offset;
};

static PyObject * FlowObjectGetter(FlowObject * self, struct RecordAttrDef * f);

#define offset( x ) offsetof( struct fts3rec_offsets, x )
#define A(n, t, x) { #n, FlowObjectGetter, NULL, NULL, &(struct RecordAttrDef){ t, x, offset(n) } },
#define B(n, t, x, z) { #n, FlowObjectGetter, NULL, NULL, &(struct RecordAttrDef){ t, x, offset(z) } },

PyGetSetDef FlowObjectGS[] = {
  A(dFlows, RF_UINT32, FT_XFIELD_DFLOWS)
  A(dOctets, RF_UINT32, FT_XFIELD_DOCTETS)
  A(dPkts, RF_UINT32, FT_XFIELD_DPKTS)
  A(dst_as, RF_UINT16, FT_XFIELD_DST_AS)
  A(dst_mask, RF_UINT8, FT_XFIELD_DST_MASK)
  A(dst_tag, RF_UINT32, FT_XFIELD_DST_TAG)
  A(dstaddr, RF_ADDR, FT_XFIELD_DSTADDR)
  B(dstaddr_raw, RF_UINT32, FT_XFIELD_DSTADDR, dstaddr)
  A(dstport, RF_UINT16, FT_XFIELD_DSTPORT)
  A(engine_id, RF_UINT8, FT_XFIELD_ENGINE_ID)
  A(engine_type, RF_UINT8, FT_XFIELD_ENGINE_TYPE)
  A(exaddr, RF_ADDR, FT_XFIELD_EXADDR)
  A(extra_pkts, RF_UINT32, FT_XFIELD_EXTRA_PKTS)
  B(first, RF_TIME, FT_XFIELD_FIRST, First)
  B(first_raw, RF_UINT32, FT_XFIELD_FIRST, First)
  A(in_encaps, RF_UINT8, FT_XFIELD_IN_ENCAPS)
  A(input, RF_UINT16, FT_XFIELD_INPUT)
  B(last, RF_TIME, FT_XFIELD_LAST, Last)
  B(last_raw, RF_UINT32, FT_XFIELD_LAST, Last)
  A(marked_tos, RF_UINT8, FT_XFIELD_MARKED_TOS)
  A(nexthop, RF_ADDR, FT_XFIELD_NEXTHOP)
  B(nexthop_raw, RF_UINT32, FT_XFIELD_NEXTHOP, nexthop)
  A(out_encaps, RF_UINT8, FT_XFIELD_OUT_ENCAPS)
  A(output, RF_UINT16, FT_XFIELD_OUTPUT)
  A(peer_nexthop, RF_ADDR, FT_XFIELD_PEER_NEXTHOP)
  B(peer_nexthop_raw, RF_UINT32, FT_XFIELD_PEER_NEXTHOP, peer_nexthop)
  A(prot, RF_UINT8, FT_XFIELD_PROT)
  A(router_sc, RF_UINT32, FT_XFIELD_ROUTER_SC)
  A(src_as, RF_UINT16, FT_XFIELD_SRC_AS)
  A(src_mask, RF_UINT8, FT_XFIELD_SRC_MASK)
  A(src_tag, RF_UINT32, FT_XFIELD_SRC_TAG)
  A(srcaddr, RF_ADDR, FT_XFIELD_SRCADDR)
  B(srcaddr_raw, RF_UINT32, FT_XFIELD_SRCADDR, srcaddr)
  A(srcport, RF_UINT16, FT_XFIELD_SRCPORT)
  A(sysUpTime, RF_UINT32, FT_XFIELD_SYSUPTIME)
  A(tcp_flags, RF_UINT8, FT_XFIELD_TCP_FLAGS)
  A(tos, RF_UINT8, FT_XFIELD_TOS)
  A(unix_nsecs, RF_UINT32, FT_XFIELD_UNIX_NSECS)
  A(unix_secs, RF_UINT32, FT_XFIELD_UNIX_SECS)
  { NULL }
};

#undef A
#undef B
#undef offset

// End define flow attributes

static PyObject *FlowToolsError;

void initFlows( void );

static void FlowSetObjectDelete( FlowSetObject *self );
static PyObject *FlowSetObjectIter( FlowSetObject *o );
static PyObject *FlowSetObjectIterNext( FlowSetObject *o );
static int FlowSet_init(FlowSetObject *self, PyObject *args, PyObject* kwds);

PyTypeObject FlowSetType = {
        PyObject_HEAD_INIT(&PyType_Type)
        0,                                      /* ob_size */
        "flowtools.FlowSet",                    /* tp_name */
        sizeof( FlowSetObject),                 /* tp_basicsize */
        0,                                      /* tp_itemsize */
        (destructor)FlowSetObjectDelete,        /* tp_dealloc */
        0,                                      /* tp_print */
        0,      /* tp_getattr */
        0,                                      /* tp_setattr */
        0,                                      /* tp_compare */
        (reprfunc)0,                            /* tp_repr */
        0,                                      /* tp_as_number */
        0,                                      /* tp_as_sequence */
        0,                                      /* tp_as_mapping */
        (hashfunc)0,                            /* tp_hash */
        (ternaryfunc)0,                         /* tp_call */
        0,                                      /* tp_str */
        (getattrofunc)0,                        /* tp_getattro */
        (setattrofunc)0,                        /* tp_setattro */
        0,                                      /* tp_as_buffer */
        Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_ITER,                   /* tp_flags */
        "Stream of netflow data",                                      /* tp_doc */
        (traverseproc)0,                        /* tp_traverse */
        (inquiry)0,                             /* tp_clear */
        0,                                      /* tp_richcompare */
        0,                                      /* tp_weaklistoffset */
        (getiterfunc)FlowSetObjectIter,         /* tp_iter */
        (iternextfunc)FlowSetObjectIterNext,    /* tp_iternext */
        0,                                      /* tp_methods */
        0,                                      /* tp_members */
        0,                                      /* tp_getset */
        0,                                      /* tp_base */
        0,                                      /* tp_dict */
        0,                                      /* tp_descr_get */
        0,                                      /* tp_descr_set */
        0,                                      /* tp_dictoffset */
        (initproc) FlowSet_init,                /* tp_init */
};

static void FlowObjectDelete( FlowObject *self );
static PyObject *FlowObjectGetID( FlowObject *self, PyObject* args );

static struct PyMethodDef FlowMethods[] = {
    { "getID", (PyCFunction)FlowObjectGetID, METH_VARARGS, "Return flow ID" },
    { NULL, NULL}	
};

PyTypeObject FlowType = {
        PyObject_HEAD_INIT(&PyType_Type)
        0,                                      /* ob_size */
        "flowtools.Flow",                       /* tp_name */
        sizeof( FlowObject),                    /* tp_basicsize */
        0,                                      /* tp_itemsize */
        (destructor)FlowObjectDelete,           /* tp_dealloc */
        0,                                      /* tp_print */
        0, // (getattrfunc)FlowObjectGetAttr,         /* tp_getattr */
        0,                                      /* tp_setattr */
        0,                                      /* tp_compare */
        (reprfunc)0,                            /* tp_repr */
        0,                                      /* tp_as_number */
        0,                                      /* tp_as_sequence */
        0,                                      /* tp_as_mapping */
        (hashfunc)0,                            /* tp_hash */
        (ternaryfunc)0,                         /* tp_call */
        0,                                      /* tp_str */
        (getattrofunc)0,                        /*tp_getattro*/
        (setattrofunc)0,                        /* tp_setattro */
        0,                                      /* tp_as_buffer */
        Py_TPFLAGS_DEFAULT,                     /* tp_flags */
        "Flow objects",                         /* tp_doc */
        (traverseproc)0,                        /* tp_traverse */
        (inquiry)0,                             /* tp_clear */
        0,                                      /* tp_richcompare */
        0,                                      /* tp_weaklistoffset */
        0,                                      /*tp_iter*/
        0,                                      /*tp_iternext*/
        FlowMethods,                                      /* tp_methods */
        0,                                      /* tp_members */
        FlowObjectGS,                                      /* tp_getset */
        0,                                      /* tp_base */
        0,                                      /* tp_dict */
        0,                                      /* tp_descr_get */
        0,                                      /* tp_descr_set */
        0,                                      /* tp_dictoffset */
        0,                                      /* tp_init */
        0,                                      /* tp_alloc */
        0,                                      /* tp_new */
        0,                                      /* tp_free */
        0,                                      /* tp_is_gc */
};

static int FlowSet_init(FlowSetObject *self, PyObject *args, PyObject *kwds) {

    static char * kwlist[] = {
        "filename", "for_writing", NULL
    };

    char* file = NULL;
    PyObject * for_writing = NULL;

    struct ftver version = { 0 };
    int res = 0;
    int bForWriting = 0;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "|sO", kwlist, &file, &for_writing) )
        return -1; 

    if (for_writing && PyBool_Check(for_writing) && (for_writing == Py_True))
      bForWriting = 1;

    if( file && strcmp( file , "-" ) != 0 ){
        Py_BEGIN_ALLOW_THREADS
        self->fd = open( file, bForWriting ? (O_CREAT | O_WRONLY) : O_RDONLY );
        Py_END_ALLOW_THREADS

        if( self->fd < 0 ){
            PyErr_SetFromErrnoWithFilename( PyExc_IOError, file );
            return -1;
        }
    }

    Py_BEGIN_ALLOW_THREADS
    res = ftio_init( &self->io, self->fd, bForWriting ? (FT_IO_FLAG_WRITE | FT_IO_FLAG_ZINIT | FT_IO_FLAG_NO_SWAP) : 
      (FT_IO_FLAG_READ | FT_IO_FLAG_MMAP));
    Py_END_ALLOW_THREADS

    if( res ) {
        PyErr_SetString( FlowToolsError, "ftio_init() failed" );
        return -1;
    }

    self->ftio_init_complete = 1;

    Py_BEGIN_ALLOW_THREADS

    if (bForWriting) {
    } else {
      ftio_get_ver( &self->io, &version );
      fts3rec_compute_offsets( &self->offsets, &version );

      self->xfield = ftio_xfield( &self->io );
    }

    Py_END_ALLOW_THREADS

    return 0;
}

static void FlowSetObjectDelete( FlowSetObject *self )
{
    if (self->ftio_init_complete) {
      Py_BEGIN_ALLOW_THREADS
      ftio_close( &(self->io) );
      Py_END_ALLOW_THREADS
    }

    if( self->fd ) {
      Py_BEGIN_ALLOW_THREADS
      close( self->fd );
      Py_END_ALLOW_THREADS
    }

    self->ob_type->tp_free(self);
}

static PyObject *FlowSetObjectIter( FlowSetObject *self )
{
    if ((self->io.flags & FT_IO_FLAG_READ) == 0) {
      PyErr_SetNone(PyExc_ValueError);
      return NULL;
    }

    Py_XINCREF(self);
    return (PyObject *)self;
}

static PyObject *FlowSetObjectIterNext( FlowSetObject *self )
{
    FlowObject *flow;
    char *record;
    
    if ((self->io.flags & FT_IO_FLAG_READ) == 0) {
      PyErr_SetNone(PyExc_ValueError);
      return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    
    record = ftio_read( &self->io );

    Py_END_ALLOW_THREADS
    
    if( ! record ){
        PyErr_SetNone( PyExc_StopIteration );
        return NULL;
    }
    
	flow = PyObject_NEW( FlowObject, &FlowType );
    if( ! flow ) return NULL;
    flow->record = record;
    flow->set = self;
    Py_XINCREF( self );
    
    return (PyObject *)flow;
}

static void FlowObjectDelete( FlowObject *self )
{
    Py_XDECREF( self->set );
    self->ob_type->tp_free(self);
}

#define getoffset( f ) ( * ( (u_int16 *)( (void *)( &self->set->offsets ) + f->offset ) ) )

static PyObject * FlowObjectGetter(FlowObject * self, struct RecordAttrDef * f) {
  u_int32 addr;
  u_int32 unix_secs, unix_nsecs, sysUpTime;
  struct fttime time;

  if( ! ( self->set->xfield & f->xfield ) ){
    PyErr_SetString( FlowToolsError, "Attribute not supported by flow type" );
    return NULL;
  }

  switch (f->type) {
    case RF_ADDR:
      addr = ntohl( *( (u_int32 *)( self->record + getoffset( f ) ) ) );
      return Py_BuildValue( "s",  (char *) inet_ntoa( *(struct in_addr *)&addr ) );

    case RF_UINT8:
      return Py_BuildValue( "i", (int) *( (u_int8 *)( self->record + getoffset( f ) ) ) );

    case RF_UINT16:
      return Py_BuildValue( "i", (int) *( (u_int16 *)( self->record + getoffset( f ) ) ) );

    case RF_UINT32:
      return PyLong_FromUnsignedLong( (unsigned long)*( (u_int32 *)( self->record + getoffset( f ) ) ) );

    case RF_TIME:
      unix_secs = *( (u_int32 *)( self->record + self->set->offsets.unix_secs ) );
      unix_nsecs = *( (u_int32 *)( self->record + self->set->offsets.unix_nsecs ) );
      sysUpTime = *( (u_int32 *)( self->record + self->set->offsets.sysUpTime ) );
      time = ftltime( sysUpTime, unix_secs, unix_nsecs,
        *( (u_int32 *)( self->record + getoffset( f ) ) ) );
      return Py_BuildValue( "f", time.secs + time.msecs * 1e-3 );
  }

  return NULL;
}   

static PyObject *FlowObjectGetID( FlowObject *self, PyObject *args )
{
    char buffer[18];
    char src[8];
    char dst[8];
    int bidir = 0;
    char *p;
    
    if( ! PyArg_ParseTuple( args, "|i", &bidir ) ) return NULL;

    p = src;
    memcpy( p, self->record + self->set->offsets.srcaddr, sizeof( u_int32 ) );
    p += sizeof( u_int32 );
    memcpy( p, self->record + self->set->offsets.srcport, sizeof( u_int16 ) );
    p += sizeof( u_int16 );
    memcpy( p, self->record + self->set->offsets.input, sizeof( u_int16 ) );
    
    p = dst;
    memcpy( p, self->record + self->set->offsets.dstaddr, sizeof( u_int32 ) );
    p += sizeof( u_int32 );
    memcpy( p, self->record + self->set->offsets.dstport, sizeof( u_int16 ) );
    p += sizeof( u_int16 );
    memcpy( p, self->record + self->set->offsets.output, sizeof( u_int16 ) );
    
    p = buffer;
    if( ( ! bidir ) || ( memcmp( src, dst, sizeof( src ) ) < 0 ) ){
        memcpy( p, src, sizeof( src ) );
        p += sizeof( src );
        memcpy( p, dst, sizeof( dst ) );
        p += sizeof( dst );
    }
    else{
        memcpy( p, dst, sizeof( dst ) );
        p += sizeof( dst ); 
        memcpy( p, src, sizeof( src ) );
        p += sizeof( src );
    }

    memcpy( p, self->record + self->set->offsets.prot, sizeof( u_int8 ) );
        
    return Py_BuildValue( "s#", buffer, sizeof( buffer ) );
}

static struct PyMethodDef FlowToolsMethods[] = {
    { NULL }
};


void initflowtools()
{
    PyObject *d, *m;

    FlowSetType.tp_new = PyType_GenericNew;
    FlowType.tp_new = PyType_GenericNew;

    if ((PyType_Ready(&FlowSetType) < 0) || (PyType_Ready(&FlowType) < 0))
      return;


    m = Py_InitModule3( "flowtools", FlowToolsMethods, "test" );
    
    Py_INCREF(&FlowSetType);
    PyModule_AddObject(m, "FlowSet", (PyObject *)&FlowSetType);

    d = PyModule_GetDict( m );
    FlowToolsError = PyErr_NewException( "flowtools.Error", NULL, NULL );
    PyDict_SetItemString( d, "Error", FlowToolsError );
}

