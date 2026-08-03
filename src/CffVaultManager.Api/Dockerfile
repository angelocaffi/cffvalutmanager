# Build context is the repository root (docker-compose sets it explicitly) because this project
# references sibling projects outside src/CffVaultManager.Api — see docker-compose.yml.
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY src/CffVaultManager.Domain/CffVaultManager.Domain.csproj src/CffVaultManager.Domain/
COPY src/CffVaultManager.Application/CffVaultManager.Application.csproj src/CffVaultManager.Application/
COPY src/CffVaultManager.Crypto/CffVaultManager.Crypto.csproj src/CffVaultManager.Crypto/
COPY src/CffVaultManager.Infrastructure/CffVaultManager.Infrastructure.csproj src/CffVaultManager.Infrastructure/
COPY src/CffVaultManager.Api/CffVaultManager.Api.csproj src/CffVaultManager.Api/
RUN dotnet restore src/CffVaultManager.Api/CffVaultManager.Api.csproj

COPY src/CffVaultManager.Domain/ src/CffVaultManager.Domain/
COPY src/CffVaultManager.Application/ src/CffVaultManager.Application/
COPY src/CffVaultManager.Crypto/ src/CffVaultManager.Crypto/
COPY src/CffVaultManager.Infrastructure/ src/CffVaultManager.Infrastructure/
COPY src/CffVaultManager.Api/ src/CffVaultManager.Api/

RUN dotnet publish src/CffVaultManager.Api/CffVaultManager.Api.csproj -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app .

# No HTTPS binding inside the container by design: TLS termination is expected to happen at a
# reverse proxy in front of this container (not part of this compose file) — see docs/deployment.md.
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

ENTRYPOINT ["dotnet", "CffVaultManager.Api.dll"]
