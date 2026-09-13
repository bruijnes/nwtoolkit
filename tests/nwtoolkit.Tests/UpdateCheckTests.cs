using Xunit;

namespace Nwtoolkit.Tests;

public class UpdateCheckTests
{
    [Theory]
    [InlineData("v1.29", "1.28", true)]
    [InlineData("1.28", "1.28", false)]
    [InlineData("v1.27", "1.28", false)]
    [InlineData("2.0", "1.28", true)]
    [InlineData("v1.28.1", "1.28", true)]
    [InlineData("garbage", "1.28", false)]
    [InlineData("", "1.28", false)]
    public void ComparesVersions(string candidate, string current, bool newer)
    {
        Assert.Equal(newer, UpdateCheck.IsNewer(candidate, current));
    }

    [Fact]
    public void NormalizesTags()
    {
        Assert.Equal("1.29", UpdateCheck.Normalize(" v1.29 "));
        Assert.Equal("1.29", UpdateCheck.Normalize("1.29"));
    }
}
