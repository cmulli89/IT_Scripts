function Get-RedactionMap {
    <#
    .SYNOPSIS
        Lists the tokens in a saved map with their type and how many originals each stands for.

    .DESCRIPTION
        Reads a map saved by Protect-Output -MapPath and returns one object per token, ordered by type then token:
        Token, Type and Count (the originals recorded for the token: one, plus any aliases such as a NetBIOS name
        that shares its domain's token). Original values never leave the function unless -ShowOriginal is given;
        then an Original property holds them (several are joined with ', '). Secrets are never in a map.

    .PARAMETER MapPath
        Map file saved by Protect-Output -MapPath. A bare file name is looked up in the per-user maps folder.

    .PARAMETER ShowOriginal
        Add an Original property with the original value(s). Local use only.

    .EXAMPLE
        Get-RedactionMap -MapPath .\session1.redactmap.json | Format-Table

    .EXAMPLE
        Get-RedactionMap -MapPath session1.redactmap.json -ShowOriginal

    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType('RedactOutput.MapEntry')]
    param(
        [Parameter(Mandatory)][string]$MapPath,
        [switch]$ShowOriginal
    )

    $rows = foreach ($group in (Read-RedactMap -Path (Resolve-RedactMapPath -MapPath $MapPath)).Entries | Group-Object -Property Token) {
        # The first entry of a token is the one that allocated it, so it carries the token's own type.
        $row = [ordered]@{ PSTypeName = 'RedactOutput.MapEntry'; Token = $group.Name; Type = $group.Group[0].Type; Count = $group.Count }
        if ($ShowOriginal) { $row['Original'] = $group.Group.Original -join ', ' }
        [pscustomobject]$row
    }
    $rows | Sort-Object -Property Type, Token
}
