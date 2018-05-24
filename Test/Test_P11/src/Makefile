
all:
	g++ *.c $(WST_BUILD_CFG) -o test_p11 -I../../../build/ubuntu_CMS/include -L../../../build/ubuntu_CMS/lib/$(BUILD_BIT)/ -lCMApi -lwsm_pcs -lCommon -lchannel -lwbcrypto -l:libssl.so.1.0.0 -l:libcrypto.so.1.0.0 -lprotobuf -lpthread -lm -ldl
clean:
	@rm -f test_p11
