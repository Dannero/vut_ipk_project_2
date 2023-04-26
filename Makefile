all: clean restore build

restore:
	dotnet restore -r linux-x64 src/

build:
	dotnet publish src/ipk-sniffer.csproj -o out/ -c Release -r linux-x64 --no-self-contained
	cp out/ipk-sniffer ./ipk-sniffer

clean:
	rm -rf ./out
	rm -rf src/obj
	rm -rf src/bin
	rm -rf ./ipk-sniffer
	dotnet clean src/