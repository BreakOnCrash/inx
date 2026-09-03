build:
	clang -framework Foundation inx.m -o bin/inx
example:
	clang -shared -framework Foundation examples/example_dylib.m -o tests/libexample.dylib
	clang -shared -framework Foundation examples/example_choose.m -o tests/libchoose.dylib
	clang -framework Foundation examples/example_tap1000.m -o tests/example_tap1000
