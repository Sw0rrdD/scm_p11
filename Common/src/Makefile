
all:
	gcc LogMsg.c WaOsPal.c $(WST_BUILD_CFG) -fPIC -shared -o libCommon.so -I../include -lpthread -lrt 

clean:
	@rm -f *.o *.d 
