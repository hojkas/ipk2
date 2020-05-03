build:
	dotnet publish . -p:PublishSingleFile=true -v m -c Release -r linux-x64 -o .
run:
	./ipk-sniffer
clean:
	rm ipk-sniffer ipk-sniffer.pdb
	rm -rf ./bin ./obj
