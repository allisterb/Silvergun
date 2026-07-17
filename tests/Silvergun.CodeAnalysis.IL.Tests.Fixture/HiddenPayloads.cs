namespace Silvergun.CodeAnalysis.IL.Tests.Fixture;

/// <summary>
/// String constants that mimic the "encode a payload so scanners miss it" obfuscation pattern.
/// This type is a static-analysis target for the obfuscation tests: nothing here is ever executed —
/// the constants only need to appear in the assembly as <c>ldstr</c> operands, which they do because
/// each trivial accessor method returns its constant (the C# compiler inlines a <c>const string</c>
/// as an <c>ldstr</c> of the literal in the returning method's body).
/// </summary>
public class HiddenPayloads
{
    #region Fields
    /// <summary>
    /// Base64 of a byte[] whose first bytes are <c>0x4D 0x5A</c> ("MZ", the Windows PE magic).
    /// Decodes and round-trips cleanly, so it must surface as an EncodedExecutable / "Windows PE".
    /// </summary>
    public const string EncodedPeImage = "TVqQAAMfJ1OEbKG4ydrr/A1OX3GCk6S1xtfo+RorPE0=";

    /// <summary>
    /// Base64 of a byte[] whose first bytes are <c>0x50 0x4B 0x03 0x04</c> (the zip local-file magic).
    /// Decodes and round-trips cleanly, so it must surface as an EncodedArchive / "zip".
    /// </summary>
    public const string EncodedZipArchive = "UEsDBBQAAAAIABEiM0RVZneImaq7zN3u";

    /// <summary>
    /// Base64 of a byte[] whose first bytes are <c>0x1F 0x8B</c> (the gzip magic). Decodes and
    /// round-trips cleanly, so it must surface as an EncodedArchive / "gzip".
    /// </summary>
    public const string EncodedGzipArchive = "H4sIAAAAAAAAA+3BAQ0AAA==";

    /// <summary>
    /// A hex-encoded byte[] whose first bytes are <c>0x7F 0x45 0x4C 0x46</c> (the ELF magic).
    /// The string is an even-length run of hex digits (matching the hex regex) and is well over the
    /// minimum encoded length, so it must surface as an EncodedExecutable / "ELF" via the hex-decode path.
    /// </summary>
    public const string EncodedElfExecutableHex = "7f454c46020101000000000000000000";

    /// <summary>
    /// A long, plain-English sentence with spaces and punctuation. It is well over the minimum length
    /// but is not valid base64/hex (spaces break the alphabet), so it must produce NO finding —
    /// a false-positive guard against flagging ordinary long strings on entropy alone.
    /// </summary>
    public const string PlainEnglishSentence =
        "the meeting notes were shared with the whole team before lunch on a very ordinary and quiet afternoon";

    /// <summary>
    /// A benign, valid base64 string that is shorter than the minimum encoded length, so it must
    /// produce NO finding regardless of what it decodes to.
    /// </summary>
    public const string ShortBenignBase64 = "AQID";
    #endregion

    #region Methods
    /// <summary>Surfaces <see cref="EncodedPeImage"/> as an <c>ldstr</c> operand.</summary>
    public string GetEncodedPeImage() => EncodedPeImage;

    /// <summary>Surfaces <see cref="EncodedZipArchive"/> as an <c>ldstr</c> operand.</summary>
    public string GetEncodedZipArchive() => EncodedZipArchive;

    /// <summary>Surfaces <see cref="EncodedGzipArchive"/> as an <c>ldstr</c> operand.</summary>
    public string GetEncodedGzipArchive() => EncodedGzipArchive;

    /// <summary>Surfaces <see cref="EncodedElfExecutableHex"/> as an <c>ldstr</c> operand.</summary>
    public string GetEncodedElfExecutableHex() => EncodedElfExecutableHex;

    /// <summary>Surfaces <see cref="PlainEnglishSentence"/> as an <c>ldstr</c> operand.</summary>
    public string GetPlainEnglishSentence() => PlainEnglishSentence;

    /// <summary>Surfaces <see cref="ShortBenignBase64"/> as an <c>ldstr</c> operand.</summary>
    public string GetShortBenignBase64() => ShortBenignBase64;
    #endregion
}
