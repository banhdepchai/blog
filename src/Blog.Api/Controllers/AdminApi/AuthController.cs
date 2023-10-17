using Blog.Api.Extensions;
using Blog.Api.Services;
using Blog.Core.Identity;
using Blog.Core.Models.Auth;
using Blog.Core.Models.System;
using Blog.Core.SeedWorks.Constants;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Security.Claims;
using System.Text.Json;

namespace Blog.Api.Controllers.AdminApi
{
	[Route("api/admin/auth")]
	[ApiController]
	public class AuthController : ControllerBase
	{
		public readonly UserManager<AppUser> _userManager;
		public readonly SignInManager<AppUser> _signInManager;
		public readonly ITokenService _tokenService;
		public readonly RoleManager<AppRole> _roleManager;

		public AuthController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, ITokenService tokenService, RoleManager<AppRole> roleManager)
		{
			_userManager = userManager;
			_signInManager = signInManager;
			_tokenService = tokenService;
			_roleManager = roleManager;
		}

		[HttpPost]
		public async Task<ActionResult<AuthenticatedResult>> Login([FromBody] LoginRequest request)
		{
			// Authentication
			if(request == null)
			{
				return BadRequest("Invalid request");
			}

			var user = await _userManager.FindByNameAsync(request.UserName);
			if(user == null || user.IsActive == false || user.LockoutEnabled)
			{
				return Unauthorized();
			}

			var result = await _signInManager.PasswordSignInAsync(request.UserName, request.Password, false, true);
			if (!result.Succeeded)
			{
				return Unauthorized();
			}

			// Authorization
			var roles = await _userManager.GetRolesAsync(user);
			var permissions = await this.GetPermissonsByUserIdAsync(user.Id.ToString());
			var claims = new[]
			{
				new Claim(JwtRegisteredClaimNames.Email, user.Email),
				new Claim(UserClaims.Id, user.Id.ToString()),
				new Claim(ClaimTypes.NameIdentifier, user.UserName),
				new Claim(ClaimTypes.Name, user.UserName),
				new Claim(UserClaims.FirstName, user.FirstName),
				new Claim(UserClaims.Roles, string.Join(";", roles)),
				new Claim(UserClaims.Permissions, JsonSerializer.Serialize(permissions)),
				new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
			};
			var accessToken = _tokenService.GenerateAccessToken(claims);
			var refreshToken = _tokenService.GenerateRefreshToken();

			user.RefreshToken = refreshToken;
			user.RefreshTokenExpiryTime = DateTime.Now.AddDays(30);
			await _userManager.UpdateAsync(user);

			return Ok(new AuthenticatedResult() { 
				Token = accessToken,
				RefreshToken = refreshToken
			});
		}

		private async Task<List<string>> GetPermissonsByUserIdAsync(string userId)
		{
			var user = await _userManager.FindByIdAsync(userId);
			var roles = await _userManager.GetRolesAsync(user);
			var permissons = new List<string>();

			var allPermissons = new List<RoleClaimsDto>();
			if(roles.Contains(Roles.Admin))
			{
				var types = typeof(Permissions).GetTypeInfo().DeclaredNestedTypes;
				foreach(var type in types)
				{
					allPermissons.GetPermissions(type);
				}
				permissons.AddRange(allPermissons.Select(x => x.Value));
			}
			else
			{
				foreach(var roleName in roles)
				{
					var role = await _roleManager.FindByNameAsync(roleName);
					var claims = await _roleManager.GetClaimsAsync(role);
					var roleClaimValues  = claims.Select(x => x.Value).ToList();
					permissons.AddRange(roleClaimValues);
				}
			}
			return permissons.Distinct().ToList();
		}
	}
}
