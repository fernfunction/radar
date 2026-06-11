using Radar.Core.Model;

namespace Radar.Core.Tests;

/// <summary>Fábrica de execuções para os testes.</summary>
public static class TestData
{
    public static ProcessExecution Execution(
        string path = @"C:\Users\alice\AppData\Local\Temp\payload.exe",
        string? commandLine = null,
        SignatureStatus signature = SignatureStatus.Unsigned,
        string? signerSubject = null,
        bool isMicrosoftRoot = false,
        DateTimeOffset? created = null,
        TimeSpan? duration = null,
        string? creatorImage = @"C:\Windows\explorer.exe",
        int creatorPid = 100,
        int declaredParentPid = 100,
        MarkOfTheWeb? motw = null,
        string? sha256 = "AABBCCDD00112233445566778899AABBCCDD00112233445566778899AABBCCDD")
    {
        var createdUtc = created ?? new DateTimeOffset(2026, 6, 10, 12, 0, 0, TimeSpan.Zero);
        return new ProcessExecution
        {
            ExecutionId = Guid.NewGuid(),
            Pid = 4242,
            CreatedUtc = createdUtc,
            ExitedUtc = duration is { } d ? createdUtc + d : null,
            CommandLine = commandLine,
            Binary = new BinaryIdentity
            {
                Path = path,
                Sha256 = sha256,
                SizeBytes = 123_456,
                Signature = new SignatureInfo
                {
                    Status = signature,
                    Subject = signerSubject,
                    IsMicrosoftRoot = isMicrosoftRoot,
                },
                Motw = motw,
            },
            Security = new SecurityContext
            {
                UserName = @"PC\alice",
                AccountKind = AccountKind.InteractiveUser,
                IntegrityLevel = IntegrityLevel.Medium,
                SessionId = 1,
            },
            CreatorPid = creatorPid,
            CreatorImage = creatorImage,
            DeclaredParentPid = declaredParentPid,
            DeclaredParentImage = creatorImage,
        };
    }
}
