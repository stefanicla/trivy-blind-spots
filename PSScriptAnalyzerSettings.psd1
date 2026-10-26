@{
    # Used by CI (.github/workflows/ci.yml) and for local linting:
    #   Invoke-ScriptAnalyzer -Path ./scripts -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
    Severity     = @('Error', 'Warning')

    ExcludeRules = @(
        # The scripts are interactive lab tools: progress and summaries are meant for the
        # console, not the pipeline, which carries the data objects (e.g. Convert-Report.ps1).
        'PSAvoidUsingWriteHost'
    )
}
