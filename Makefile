build:
	dotnet publish zeta/ipk-sniffer/ipk-sniffer.csproj -p:PublishSingleFile=true -r linux-x64 -o .
run:
	./ipk-sniffer
clean:
	rm ipk-sniffer ipk-sniffer.pdb
