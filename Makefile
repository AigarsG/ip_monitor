TARGET = monitor
SRC = $(TARGET).c
OBJ = $(SRC:.c=.o)
CFLAGS = -Wall -Werror --std=c89 -I.

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $^ -o $@

$(OBJ): $(SRC)
	$(CC) $(CFLAGS) -c $^ -o $@

.PHONY: clean
clean:
	$(RM) $(TARGET) $(OBJ)