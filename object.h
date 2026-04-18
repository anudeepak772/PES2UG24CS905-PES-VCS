#ifndef OBJECT_H
#define OBJECT_H

#include "pes.h" // This "borrows" ObjectID and ObjectType from the main file

// ONLY put function prototypes here. 
// Do NOT redefine struct ObjectID or enum ObjectType!
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);

#endif
