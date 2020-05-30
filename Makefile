all:
	javac crypto/Main.java crypto/tools/*.java crypto/cipher/*.java crypto/examples/*.java

clean:	
	rm -rf crypto/*.class crypto/tools/*.class crypto/cipher/*.class crypto/examples/*.class
	
run:
	java crypto/Main
