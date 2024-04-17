int main(int argc, char **argv)
{
    char *sh_path;

    if (atoi(argv[1]) == 423)
    {
        sh_path = strdup("/bin/sh");

        gid_t gid = getegid();
        uid_t uid = geteuid();

        setresgid(gid, gid, gid);
        setresuid(uid, uid, uid);
        
        execv("/bin/sh", &sh_path);
    }
    else
    {
        fwrite("No !\n", 1, 5, stderr);
    }

    return 0;
}