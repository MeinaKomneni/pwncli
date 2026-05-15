// Generic vulnerable program for testing IO_FILE house techniques
// Provides: alloc, free, edit, show, and an arbitrary write primitive
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_CHUNKS 16

char *chunks[MAX_CHUNKS];
size_t chunk_sizes[MAX_CHUNKS];

void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void menu() {
    puts("1. alloc");
    puts("2. free");
    puts("3. edit");
    puts("4. show");
    puts("5. arb_write");
    puts("6. exit");
    printf("> ");
}

void do_alloc() {
    int idx;
    size_t size;
    printf("idx: ");
    scanf("%d", &idx);
    if (idx < 0 || idx >= MAX_CHUNKS) return;
    printf("size: ");
    scanf("%lu", &size);
    chunks[idx] = malloc(size);
    chunk_sizes[idx] = size;
    printf("addr: %p\n", chunks[idx]);
}

void do_free() {
    int idx;
    printf("idx: ");
    scanf("%d", &idx);
    if (idx < 0 || idx >= MAX_CHUNKS) return;
    free(chunks[idx]);
}

void do_edit() {
    int idx;
    printf("idx: ");
    scanf("%d", &idx);
    if (idx < 0 || idx >= MAX_CHUNKS) return;
    printf("data: ");
    read(0, chunks[idx], chunk_sizes[idx]);
}

void do_show() {
    int idx;
    printf("idx: ");
    scanf("%d", &idx);
    if (idx < 0 || idx >= MAX_CHUNKS) return;
    printf("data: ");
    write(1, chunks[idx], chunk_sizes[idx]);
}

void do_arb_write() {
    unsigned long addr;
    size_t len;
    printf("addr: ");
    scanf("%lu", &addr);
    printf("len: ");
    scanf("%lu", &len);
    printf("data: ");
    read(0, (void *)addr, len);
}

int main() {
    init();
    while (1) {
        menu();
        int choice;
        scanf("%d", &choice);
        switch (choice) {
            case 1: do_alloc(); break;
            case 2: do_free(); break;
            case 3: do_edit(); break;
            case 4: do_show(); break;
            case 5: do_arb_write(); break;
            case 6: exit(0);
            default: break;
        }
    }
    return 0;
}
