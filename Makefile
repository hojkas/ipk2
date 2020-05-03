build:
	dotnet publish . -p:PublishSingleFile=true -c Release -r linux-x64 -o .
run:
	./ipk-sniffer -i any
clean:
	rm ipk-sniffer ipk-sniffer.pdb
	rm -rf ./bin ./obj
