namespace SharedLibraries
{
    public interface IKeyProvider
    {
        byte[] GetPrivateKey(string nodeId);
    }
}
