TARGET = monitor
SRC = $(TARGET).c
OBJ = $(SRC:.c=.o)
CFLAGS = -Wall -Werror --std=c99 -I. -D_POSIX_C_SOURCE=200809L

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $^ -o $@

$(OBJ): $(SRC)
	$(CC) $(CFLAGS) -c $^ -o $@

.PHONY: clean
clean:
	$(RM) $(TARGET) $(OBJ)