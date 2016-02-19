/* .pcap communication statistics reporter
 * Written by Peter Pilarski
 * Requires tshark
 */
#include <iostream>//cin,cout,getline
#include <sstream>//istringstream
#include <string>//string,stoi(C++11)
#include <cstring>//strlen
#include <sys/stat.h>//stat
#include <algorithm>//sort

typedef std::vector<std::string> vect_str;

struct Comm{
	int cnt, siz;//Packet count, byte count
	std::string src, dst, pro;//IP src, IP dst, protocol
};

vect_str split(const char*);
void outComms(std::vector<Comm>&, bool);
void parseComm(std::vector<Comm>&, vect_str&, bool);
bool parseArgs(int&, char**, std::string&, bool&, bool&);
bool compareCnt(const Comm&, const Comm&);
bool compareSiz(const Comm&, const Comm&);
Comm addComm (vect_str&, bool);
bool fileExists(char*);
void usage(char*);

int main(int argc, char** argv){
	bool proto=0;	// Group comms by protocol
	bool sort=0;	// 0=frames, 1=bytes
	std::string cmd="tshark -r ";
	if(!parseArgs(argc, argv, cmd, proto, sort)){// Parse CLI args
		usage(argv[0]);
		return 0;
	}
	std::vector<Comm> comms;	// Vector of communication info
	char line[512];				// Line buffer for tshark
	FILE *tshark;
	if(!(tshark = popen(cmd.c_str(),"r"))){	// Execute tshark
		std::cout<<"ERROR."<<std::endl;
		return 0;
	}
	while(fgets(line,512,tshark)){		// Get lines from tshark
		size_t l = std::strlen(line);	// Length of line
		if(l>1 && line[l-1]=='\n'){
			line[l-1]='\0';				// Strip newline
			}
		vect_str fields=split(&*line);	// Split string by comma
		parseComm(comms, fields, proto);// Add packet to Comms
	}
	pclose(tshark);
	if(sort){	//0=frames, 1=bytes
		std::sort(comms.begin(), comms.end(), compareSiz);
	}else
		std::sort(comms.begin(), comms.end(), compareCnt);
	outComms(comms, proto);	// Print comms
}
void usage(char* self){
	std::cerr<<"Usage: "<<self<<" -b -p --file ./file.pcap"<<std::endl<<
	"\t-b, --bytes\n\t\tSort by bytes, instead of frames"<<std::endl<<
	"\t-p\n\t\tGroup communications by protocol"<<std::endl<<
	"\t-f <file>, --file <file>\n\t\tSpecify .pcap file to parse (required)."
	<<std::endl<<"\t-h, --help\n\t\tPrint this message."<<std::endl;
}
bool fileExists(char* fn){
	struct stat faBuff;//buffer for file attributes
	return(stat(fn,&faBuff)==0);//stat returns 0 is file exists
}

// Parse CLI args
bool parseArgs(int& argc, char** argv, std::string& cmd, bool& proto, bool& sort){
	if(argc<3){// Must specify --file
		return 0;
	}else{
		for(int i=1;i<argc;i++){
			if(std::string(argv[i])=="-p"){
				proto=1;
			}else if(std::string(argv[i])=="-b" || std::string(argv[i])=="--bytes"){
				sort=1;
			}else if(std::string(argv[i])=="-f" || std::string(argv[i])=="--file"){
				if(i+1<argc && fileExists(argv[++i])){
					cmd+=argv[i];
				}else{
					std::cerr<<"Error: Invalid input file!"<<std::endl;
					return 0;
					}
			}else if(std::string(argv[i])=="-h" || std::string(argv[i])=="--help"){
				return 0;
			}
		}
	}
	if(proto){// Grouping by protocol?
		cmd+=" -T fields -e ip.src -e ip.dst -e frame.len -e _ws.col.Protocol -E separator=, -E occurrence=f";
	}else{
		cmd+=" -T fields -e ip.src -e ip.dst -e frame.len -E separator=, -E occurrence=f";
	}
	return 1;// All's good!
}

// Add current packet's info to comms
void parseComm(std::vector<Comm> &comms, vect_str &fields, bool proto){
	bool seen=0;
	if(comms.size()){// Segfaults are bad, mkay?
		for(unsigned int i=0;i<comms.size();i++){
			// If this comm exists, add to it
			if(comms[i].src==fields[0] and comms[i].dst==fields[1]){
				if(proto==0 || comms[i].pro==fields[3]){// Group by protocol?
					comms[i].siz=comms[i].siz+std::stoi(fields[2]);
					comms[i].cnt++;
					seen=1;
					break;
				}
			}
		}
	}
	if(seen==0){// Comm doesn't exist
		comms.push_back(addComm(fields, proto));// Add new Comm
	}
}

// Split by comma
vect_str split(const char* line){
	vect_str fields;
	// Is there a better way to do this?
	std::istringstream ss((std::string)line);// cstring->string->stringstream
	while(!ss.eof()){
		std::string field;
		getline(ss, field, ',');
		fields.push_back(field);
	}
	return fields;
}

//Populate & return a new Comm struct
Comm addComm(vect_str &fields, bool proto){
	struct Comm newCom;
	newCom.cnt=1;
	newCom.src=fields[0];
	newCom.dst=fields[1];
	newCom.siz=std::stoi(fields[2]);
	if(proto){newCom.pro=fields[3];}
	return newCom;
}
// Compare by frame count
bool compareCnt(const Comm &a, const Comm &b){
	return a.cnt > b.cnt;
}
// Compare by byte count
bool compareSiz(const Comm &a, const Comm &b){
	return a.siz > b.siz;
}

// Output comms
void outComms(std::vector<Comm> &comms, bool proto){
	std::cout<<"Src\t\tDst\t\tFrames\tBytes\tProtocol"<<std::endl;
	for(unsigned int i=0;i<comms.size();i++){
		std::cout<<comms[i].src<<"\t"<<\
		comms[i].dst<<"\t"<<comms[i].cnt<<"\t"<<comms[i].siz;
		if(proto){std::cout<<"\t"<<comms[i].pro;}
		std::cout<<std::endl;
	}
}
