GCC = gcc
FLAGS = -W -Wall -Wextra -ansi -g -O3 -fexpensive-optimizations

# _GNU_SOURCE enables RTLD_NEXT
MACROS = -D_GNU_SOURCE

NTRACE_LIB = ntrace
SRC_DIR = src
INC_DIR = include
LINK = -ldl 
LIB_FILE = lib$(NTRACE_LIB).so

default: $(LIB_FILE)

LIB_SRCS = $(SRC_DIR)/ntrace.c \
		   $(SRC_DIR)/callback.c \
		   $(SRC_DIR)/util.c

$(LIB_FILE): $(LIB_SRCS)
	$(GCC) $(MACROS) $(FLAGS) -fPIC -shared -Wl,-soname,$(LIB_FILE) -I$(INC_DIR) -o $@ $^ $(LINK)

clean:
	rm -f $(LIB_FILE)
	
