#include <stdio.h>
#include <unistd.h>

void secret_function() {
    printf("You found the secret function!\n");
}

int main() {
    printf("Process ID: %d\n", getpid());
    printf("Address of secret_function: %p\n", &secret_function);

    while (1) {
        printf("I am an innocent program, just looping...\n");
        // In a real scenario, you might call secret_function() here.
        // For hiding, we just need it to exist in memory.
        sleep(5);
    }
    return 0;
}
