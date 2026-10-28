
CXX = g++
CXXFLAGS = -g -Wall -Wextra -std=c++11 -pthread
LDFLAGS = -pthread
SSL_LIBS = -lssl -lcrypto

SOCKET_OBJS = VSocket.o Socket.o SSLSocket.o
INVENTORY_OBJS = FileSystem.o SIQPProtocol.o

TARGETS = TLSManager.out \
          ForkMirrorServer.out \
          ThreadMirrorServer.out \
          MirrorClient.out \
          Intermediario.out \
          WebServer.out \
          MancomunadoServer.out

all: $(TARGETS)

# ==========================================
# SERVIDOR CON FORK
# ==========================================

ForkMirrorServer.out: ForkMirrorServer.o $(SOCKET_OBJS) $(INVENTORY_OBJS)
	$(CXX) $^ $(LDFLAGS) $(SSL_LIBS) -o $@

# ==========================================
# SERVIDOR CON THREADS
# ==========================================

ThreadMirrorServer.out: ThreadMirrorServer.o $(SOCKET_OBJS) $(INVENTORY_OBJS)
	$(CXX) $^ $(LDFLAGS) $(SSL_LIBS) -o $@

# ==========================================
# CLIENTE SIQP
# ==========================================

MirrorClient.out: MirrorClient.o $(SOCKET_OBJS)
	$(CXX) $^ $(LDFLAGS) $(SSL_LIBS) -o $@

# ==========================================
# INTERMEDIARIO SIQP
# ==========================================

Intermediario.out: Intermediario.o $(SOCKET_OBJS)
	$(CXX) $^ $(LDFLAGS) $(SSL_LIBS) -o $@

# ==========================================
# SERVIDOR WEB
# ==========================================

WebServer.out: WebServer.o $(SOCKET_OBJS) FileSystem.o
	$(CXX) $^ $(LDFLAGS) $(SSL_LIBS) -o $@


MancomunadoServer.out: MancomunadoServer.o FileSystem.o SIQPProtocol.o
	$(CXX) $^ $(LDFLAGS) -o $@


# ==========================================
# COMPILACION DE ARCHIVOS .cc
# ==========================================

%.o: %.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

# ==========================================
# LIMPIEZA
# ==========================================

clean:
	rm -f *.o *.out

.PHONY: all clean
# Agregar al Makefile original
TLSProvision.out: TLSProvision.cc
	$(CXX) $(CXXFLAGS) $< -lssl -lcrypto -o $@

TLSManager.out: TLSManager.cc
	$(CXX) $(CXXFLAGS) $< $(SSL_LIBS) -o $@
