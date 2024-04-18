struct s_user {
    int id;
    char login[28];
    int is_auth;
};

int *service;

struct s_user *user;

int main()
{
    while (1)
    {
        printf("%p, %p \n", user, service);

        char buffer[128];

        if (!(fgets(buffer, 128, stdin)))
            break;

        if (!(strncmp(buffer, "auth ", 5)))
        {
            user = malloc(4);
            user->id = 0;

            if (strlen(buffer + 5) <= 30)
                strcpy(user, buffer + 5);
        }

        if (!(strncmp(buffer, "reset", 5)))
            free(user);

        if (!(strncmp(buffer, "service", 6)))
            service = strdup(buffer + 7);

        if (!(strncmp(buffer, "login", 5)))
        {
            if (user->is_auth)
                system("/bin/sh");
            else
                fwrite("Password:\n", 1, 10, stdout);
        }
    }
    return 0;
}