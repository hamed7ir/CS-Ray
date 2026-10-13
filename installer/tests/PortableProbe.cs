// Run from a folder holding CS-Ray.exe + CS-Ray.portable: prints where ProfileStore puts profiles.json.
static class PortableProbe
{
    static void Main()
    {
        System.Console.WriteLine(CS_Ray.Core.Config.ProfileStore.DefaultPath);
        System.Console.WriteLine(CS_Ray.Core.Config.ProfileStore.ResolutionInfo);
    }
}
