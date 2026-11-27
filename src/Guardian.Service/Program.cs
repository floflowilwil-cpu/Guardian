using Guardian.Service.Hosting;

var builder = Host.CreateApplicationBuilder(args);
builder.UseGuardianWindowsService();
builder.Services.AddGuardianServiceCore(builder.Configuration);

using var host = builder.Build();
await host.RunAsync();
