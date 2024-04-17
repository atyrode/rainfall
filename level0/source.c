int main(int argc, char **argv)
{
    char *sh_path;

    __uid_t u_id;
    __gid_t g_id;

    if (atoi(argv[1]) == 423)
    {
        sh_path = strdup("/bin/sh");

        g_id = getegid();
        u_id = geteuid();

        setresgid(g_id, g_id, g_id);
        setresuid(u_id, u_id, u_id);
        
        execv("/bin/sh", &sh_path);
    }
    else
    {
        fwrite("No !\n", 1, 5, stderr);
    }
    return 0;
}