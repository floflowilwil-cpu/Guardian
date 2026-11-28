using Guardian.Service.Hosting;
using Guardian.Service.Storage;

var builder = Host.CreateApplicationBuilder(args);
builder.UseGuardianWindowsService();
builder.Services.AddGuardianServiceCore(builder.Configuration);
builder.Services.AddGuardianDataStorage();

using var host = builder.Build();
await host.RunAsync();
