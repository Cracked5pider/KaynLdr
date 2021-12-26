MAKEFLAGS += -s

x64:
	echo "[*] Compile Kayn x64 Reflective Loader"
	cd KaynLdr; $(MAKE) x64
	echo "[*] Compile Kayn x64 Injector"
	cd KaynInject; $(MAKE) x64
