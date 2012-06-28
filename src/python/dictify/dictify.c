/*
 * C implementation of a string parsing function (too slow in python!)
 */

/* must include this first! */
#include "Python.h"

#include <ctype.h>

/* local function prototypes */
static PyObject *dictify(PyObject *self, PyObject* args);

/* exception object raised for parsing errors */
static PyObject *ParseError;

/* methods defined by module */
static PyMethodDef methods[] = {
    {"dictify", dictify, METH_VARARGS, "Parses the input line and returns a dict of key/value pairings"},
    {NULL, NULL, 0, NULL}
};

/* why the hell are assertions broken!?  I blame python */
#define my_assert(e)                                                    \
    if (!(e)) {                                                         \
        PyErr_Format(PyExc_AssertionError,                              \
            "(%s), function %s, file %s, line %d", #e, __func__,        \
            __FILE__, __LINE__);                                        \
        Py_DECREF(d);                                                   \
        return NULL;                                                    \
    }                                                                   \
    
/* module's initialization function */
PyMODINIT_FUNC
initdictify(void)
{
    PyObject *m, *d;

    m = Py_InitModule("dictify", methods);
    ParseError = PyErr_NewException("dictify.ParseError", PyExc_StandardError,
        NULL);
    if (ParseError) {
        d = PyModule_GetDict(m);
        PyDict_SetItemString(d, "ParseError", ParseError);
    }
}

enum DICTIFY_STATE {
    DICTIFY_START_OF_KEY,
    DICTIFY_END_OF_KEY,
    DICTIFY_EQUALS_SIGN,
    DICTIFY_START_OF_VALUE,
    DICTIFY_END_OF_VALUE
};

/*
 * arguments: a string
 * return: a Python dict of key/value pairings parsed from the string
 */
static PyObject*
dictify(PyObject *self, PyObject* args)
{
    PyObject *d = PyDict_New();
    if (d == NULL)
        return NULL;

    char *line;
    if (!PyArg_ParseTuple(args, "s", &line))
        return NULL;

    char *key_tok = NULL, *key_end = NULL, *value_tok = NULL;
    enum DICTIFY_STATE state = DICTIFY_START_OF_KEY;
    char quote = '\0';  /* quoting character (NULL means no quotes) */

#define INSERT_KEYVAL(valobj)                                           \
    do {                                                                \
        my_assert(key_tok != NULL);                                     \
        my_assert(key_end != NULL);                                     \
        my_assert(key_end >= key_tok);                                  \
        PyObject *s = PyString_FromStringAndSize(key_tok,               \
            key_end - key_tok);                                         \
        if (s == NULL) {                                                \
            PyErr_SetString(PyExc_StandardError,                        \
                "PyString_FromStringAndSize failed");                   \
            Py_DECREF(d);                                               \
            return NULL;                                                \
        }                                                               \
        if (PyDict_SetItem(d, s, valobj) != 0) {                        \
            PyErr_SetString(PyExc_StandardError,                        \
                "PyDict_SetItem failed");                               \
            Py_DECREF(d);                                               \
            return NULL;                                                \
        }                                                               \
        /* PyDict_SetItem increments the refcount of both the key and value! */ \
        Py_DECREF(s);                                                   \
        Py_DECREF(valobj);                                              \
        key_tok = NULL;                                                 \
        key_end = NULL;                                                 \
        value_tok = NULL;                                               \
    } while (0)                                                         \
    
    char *ptr = line;
    for (; *ptr != '\0'; ptr++) {
        switch (state) {
        case DICTIFY_START_OF_KEY:
            if ((*ptr == '"') || (*ptr == '\'')) {
                PyErr_SetString(ParseError, "unexpected quotation mark while"
                    " parsing key");
                Py_DECREF(d);
                return NULL;
            }
            else if (!isspace(*ptr)) {
                state = DICTIFY_END_OF_KEY;
                key_tok = ptr;
            }
            break;
                
        case DICTIFY_END_OF_KEY:
            if (isspace(*ptr)) {
                key_end = ptr;
                state = DICTIFY_EQUALS_SIGN;
            }
            else if (*ptr == '=') {
                key_end = ptr;
                state = DICTIFY_START_OF_VALUE;
            }
            else if ((*ptr == '"') || (*ptr == '\'')) {
                PyErr_SetString(ParseError, "encountered quotation mark while"
                    " parsing key");
                Py_DECREF(d);
                return NULL;
            }
            else if (iscntrl(*ptr)) {
                PyErr_Format(ParseError, "encountered illegal character (%d)"
                    " while parsing key", *ptr);
                Py_DECREF(d);
                return NULL;
            }
            break;

        case DICTIFY_EQUALS_SIGN:
            if (*ptr == '=') {
                state = DICTIFY_START_OF_VALUE;
            }
            else if (!isspace(*ptr)) {
                /*
                 * we allow "value-less" items (i.e. floating tokens) to which
                 * we assign a value of None in the returned dictionary
                 */
                Py_INCREF(Py_None);
                INSERT_KEYVAL(Py_None);
                state = DICTIFY_END_OF_KEY;
                key_tok = ptr;
            }
            break;

        case DICTIFY_START_OF_VALUE:
            if ((*ptr == '"') || (*ptr == '\'')) {
                quote = *ptr;
                value_tok = ptr + 1;
                state = DICTIFY_END_OF_VALUE;
            }
            else if (!isspace(*ptr)) {
                quote = '\0';
                value_tok = ptr;
                state = DICTIFY_END_OF_VALUE;
            }
            break;

        case DICTIFY_END_OF_VALUE:
            if (*ptr == '=') {
                PyErr_SetString(ParseError, "encountered equals sign while"
                    " parsing value");
                Py_DECREF(d);
                return NULL;
            }
            else if ((*ptr == quote) || /* always false if quote == '\0' */
                ((quote == '\0') && (isspace(*ptr)))) {
                my_assert(value_tok != NULL);
                PyObject *v = PyString_FromStringAndSize(value_tok,
                    ptr - value_tok);
                if (v == NULL) {
                    PyErr_SetString(PyExc_StandardError,
                        "PyString_FromStringAndSize failed");
                    Py_DECREF(d);
                    return NULL;
                }
                INSERT_KEYVAL(v);
                state = DICTIFY_START_OF_KEY;
            }
            break;

        default:
            my_assert(0  /* invalid state */);
        }
    }

    /* check if we ended in a bad parsing state */
    switch (state) {
    case DICTIFY_START_OF_KEY:
        /* no problemo */
        break;

    case DICTIFY_END_OF_KEY:
        /* assume this is a complete (value-less) token */
        key_end = ptr;
        Py_INCREF(Py_None);
        INSERT_KEYVAL(Py_None);
        state = DICTIFY_END_OF_KEY;
        break;

    case DICTIFY_EQUALS_SIGN:
        /* assume this is a value-less token */
        Py_INCREF(Py_None);
        INSERT_KEYVAL(Py_None);
        state = DICTIFY_END_OF_KEY;
        break;

    case DICTIFY_START_OF_VALUE:
        PyErr_SetString(ParseError, "input ended before value was found");
        Py_DECREF(d);
        return NULL;

    case DICTIFY_END_OF_VALUE:
        if (quote == '\0') {
            /* assume this is a complete value */
            my_assert(value_tok != NULL);
            PyObject *v = PyString_FromStringAndSize(value_tok, ptr - value_tok);
            if (v == NULL) {
                PyErr_SetString(PyExc_StandardError,
                    "PyString_FromStringAndSize failed");
                Py_DECREF(d);
                return NULL;
            }
            INSERT_KEYVAL(v);
        }
        else {
            /* incomplete value */
            PyErr_SetString(ParseError, "input ended before complete value was found");
            Py_DECREF(d);
            return NULL;
        }
        break;

    default:
        my_assert(0);
    }
    
    return d;
}
