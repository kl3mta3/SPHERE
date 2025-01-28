namespace SharedLibraries
{
    public interface IKeyProvider
    {
        string GetPrivateKey(string nodeId);
    }
}
