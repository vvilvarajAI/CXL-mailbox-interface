CC := gcc
CFLAGS := -Wall -Wextra -g
LDFLAGS := -lpci -lpciaccess

SRCS := main.c
OBJS := $(SRCS:.c=.o)
TARGET := pci_info

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS)  $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)