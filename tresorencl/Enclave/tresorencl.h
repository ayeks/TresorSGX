#ifndef tresorencl_H
#define tresorencl_H


unsigned int inc( unsigned int input );
void enclaveChangeBuffer(char *buf, int len);
void enclaveStringSave(char *input, int len); 
void enclaveStringLoad(char *output, int len); 



#endif

