CC := gcc
CFLAGS := -Wall -Wextra -g -D_GNU_SOURCE
LDFLAGS := -lpci -lpciaccess

SRCS := main.c
OBJS := $(SRCS:.c=.o)
TARGET := pci_info

LIB_SRCS := cxl_mailbox_lib.c
LIB_OBJS := $(LIB_SRCS:.c=.o)
LIB_TARGET := libmailbox.so

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS) $(LIB_TARGET)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -L. -lmailbox

$(LIB_TARGET): $(LIB_OBJS)
	$(CC) $(CFLAGS) -shared $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) $(LIB_OBJS) $(LIB_TARGET)
