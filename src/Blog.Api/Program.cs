using Blog.Api;
using Blog.Api.Services;
using Blog.Core.ConfigOptions;
using Blog.Core.Identity;
using Blog.Core.Models.Content;
using Blog.Core.Repositories;
using Blog.Core.SeedWorks;
using Blog.Data;
using Blog.Data.Repositories;
using Blog.Data.SeedWorks;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Swashbuckle.AspNetCore.SwaggerGen;
using System.Reflection;

var builder = WebApplication.CreateBuilder(args);

var configuration = builder.Configuration;
var connectionString = configuration.GetConnectionString("DefaultConnection");

// Config Db Context and ASP.NET Core Identity
builder.Services.AddDbContext<BlogContext>(options => options.UseSqlServer(connectionString));

builder.Services.AddIdentity<AppUser, AppRole>(options => options.SignIn.RequireConfirmedAccount = false).AddEntityFrameworkStores<BlogContext>();

builder.Services.Configure<IdentityOptions>(options =>
{
	// Password settings.
	options.Password.RequireDigit = true;
	options.Password.RequireLowercase = true;
	options.Password.RequireNonAlphanumeric = true;
	options.Password.RequireUppercase = true;
	options.Password.RequiredLength = 6;
	options.Password.RequiredUniqueChars = 1;

	// Lockout settings.
	options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
	options.Lockout.MaxFailedAccessAttempts = 5;
	options.Lockout.AllowedForNewUsers = true;

	// User settings.
	options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
	options.User.RequireUniqueEmail = false;
});

// Add services to the container.
builder.Services.AddScoped(typeof(IRepository<,>), typeof(RepositoryBase<,>));
builder.Services.AddScoped<IUnitOfWork, UnitOfWork>();

// Business services and repositories
var services = typeof(PostRepository).Assembly.GetTypes()
	.Where(x => x.GetInterfaces().Any(i => i.Name == typeof(IRepository<,>).Name)
	&& !x.IsAbstract && x.IsClass && !x.IsGenericType);

foreach (var service in services)
{
	var allInterfaces = service.GetInterfaces();
	var directInterface = allInterfaces.Except(allInterfaces.SelectMany(t => t.GetInterfaces())).FirstOrDefault();
	if (directInterface != null)
	{
		builder.Services.Add(new ServiceDescriptor(directInterface, service, ServiceLifetime.Scoped));
	}
}

// AutoMapper
builder.Services.AddAutoMapper(typeof(PostInListDto));

// Authen and Author
builder.Services.Configure<JwtTokenSettings>(configuration.GetSection("JwtTokenSettings"));
builder.Services.AddScoped<SignInManager<AppUser>, SignInManager<AppUser>>();
builder.Services.AddScoped<UserManager<AppUser>, UserManager<AppUser>>();
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<RoleManager<AppRole>, RoleManager<AppRole>>();

// Default Config for ASP.NET Core
builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
	c.CustomOperationIds(apiDesc =>
	{
		return apiDesc.TryGetMethodInfo(out MethodInfo methodInfo) ? methodInfo.Name : null;
	});
	c.SwaggerDoc("AdminAPI", new Microsoft.OpenApi.Models.OpenApiInfo
	{
		Version = "v1",
		Title = "API for Administrators",
		Description = "API for CMS core domain. This domain keeps track of campaigns, campaign rules, and campaign execution."
	});
	c.ParameterFilter<SwaggerNullableParameterFilter>();
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
	app.UseSwagger();
	app.UseSwaggerUI(c =>
	{
		c.SwaggerEndpoint("AdminAPI/swagger.json", "Admin API");
		c.DisplayOperationId();
		c.DisplayRequestDuration();
	});
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

// Seeding Data
app.MigrateDatabase();

app.Run();
