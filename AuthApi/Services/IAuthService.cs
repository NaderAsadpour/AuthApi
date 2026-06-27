using AuthApi.DTOs;

namespace AuthApi.Services;

public interface IAuthService
{
    Task<TokenResponseDto?> RegisterAsync(RegisterDto request);
    Task<TokenResponseDto?> LoginAsync(LoginDto request);
    Task<TokenResponseDto?> RefreshTokenAsync(string refreshToken);
    Task<bool> RevokeTokenAsync(string refreshToken);
}
