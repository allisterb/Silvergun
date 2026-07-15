@echo off
dotnet "%~dp0src\Silvergun.CLI\bin\Debug\net10.0\Silvergun.CLI.dll" %*
exit /b %ERRORLEVEL%
