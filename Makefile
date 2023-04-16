all: clean restore build

restore:
	dotnet restore ipk-sniffer/
 
build:
	dotnet build ipk-sniffer/ -o out/ -c Release
 
run:
	dotnet run --project ipk-sniffer/ipk-sniffer.csproj
clean:
	rm -rf ./out
	rm -rf ipk-sniffer/obj
	rm -rf ipk-sniffer/bin
	dotnet clean ipk-sniffer/
 
run-clean: clean restore build run 