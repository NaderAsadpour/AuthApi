using AuthApi.Data;
using AuthApi.DTOs;
using AuthApi.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthApi.Services
{
    public class AuthService(AppDbContext _context, IConfiguration _configuration) : IAuthService
    {
        // ── Register ──────────────────────────────────
        public async Task<TokenResponseDto?> RegisterAsync(RegisterDto request)
        {
            if (await _context.Users.AnyAsync(u => u.Email == request.Email))
                return null;

            var user = new User
            {
                Username = request.Username,
                Email = request.Email,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password)
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return await GenerateTokensAsync(user);
        }

        // ── Login ─────────────────────────────────────
        public async Task<TokenResponseDto?> LoginAsync(LoginDto request)
        {
            var user = await _context.Users
                .Include(u => u.RefreshToken)
                .FirstOrDefaultAsync(u => u.Email == request.Email);

            if (user is null)
                return null;

            if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
                return null;

            return await GenerateTokensAsync(user);
        }

        // ── Refresh Token ─────────────────────────────
        public async Task<TokenResponseDto?> RefreshTokenAsync(string refreshToken)
        {
            var token = await _context.RefreshTokens
                .Include(r => r.User)
                .FirstOrDefaultAsync(r => r.Token == refreshToken);

            if (token is null || token.IsRevoked || token.ExpiresAt < DateTime.UtcNow)
                return null;

            return await GenerateTokensAsync(token.User);
        }

        // ── Revoke Token ──────────────────────────────
        public async Task<bool> RevokeTokenAsync(string refreshToken)
        {
            var token = await _context.RefreshTokens
                .FirstOrDefaultAsync(r => r.Token == refreshToken);

            if (token is null || token.IsRevoked)
                return false;

            token.IsRevoked = true;
            await _context.SaveChangesAsync();
            return true;
        }

        // ── Private Helpers ───────────────────────────
        private async Task<TokenResponseDto> GenerateTokensAsync(User user)
        {
            var accessToken = GenerateAccessToken(user);
            var refreshToken = await GenerateRefreshTokenAsync(user);

            return new TokenResponseDto
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken.Token,
                ExpiresAt = refreshToken.ExpiresAt
            };
        }

        private string GenerateAccessToken(User user)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(jwtSettings["SecretKey"]!));

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, user.Role)
            };

            var token = new JwtSecurityToken(
                issuer: jwtSettings["Issuer"],
                audience: jwtSettings["Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(
                    double.Parse(jwtSettings["AccessTokenExpirationMinutes"]!)),
                signingCredentials: new SigningCredentials(
                    key, SecurityAlgorithms.HmacSha256)
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private async Task<RefreshToken> GenerateRefreshTokenAsync(User user)
        {
            // اگه refresh token قبلی داره، revoke کن
            user.RefreshToken?.IsRevoked = true;

            var refreshToken = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                ExpiresAt = DateTime.UtcNow.AddDays(
                    double.Parse(
                        _configuration["JwtSettings:RefreshTokenExpirationDays"]!)),
                UserId = user.Id
            };

            _context.RefreshTokens.Add(refreshToken);
            await _context.SaveChangesAsync();

            return refreshToken;
        }
    }
}