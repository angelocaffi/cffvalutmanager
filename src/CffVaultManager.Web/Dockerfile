# Build context is the repository root (docker-compose sets it explicitly) because this project
# references sibling projects outside src/CffVaultManager.Web — see docker-compose.yml.
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY src/CffVaultManager.Crypto/CffVaultManager.Crypto.csproj src/CffVaultManager.Crypto/
COPY src/CffVaultManager.Web.Client/CffVaultManager.Web.Client.csproj src/CffVaultManager.Web.Client/
COPY src/CffVaultManager.Web/CffVaultManager.Web.csproj src/CffVaultManager.Web/
RUN dotnet restore src/CffVaultManager.Web/CffVaultManager.Web.csproj

COPY src/CffVaultManager.Crypto/ src/CffVaultManager.Crypto/
COPY src/CffVaultManager.Web.Client/ src/CffVaultManager.Web.Client/
COPY src/CffVaultManager.Web/ src/CffVaultManager.Web/

RUN dotnet publish src/CffVaultManager.Web/CffVaultManager.Web.csproj -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app .

# No HTTPS binding inside the container by design: TLS termination is expected to happen at a
# reverse proxy in front of this container (not part of this compose file) — see docs/deployment.md.
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

ENTRYPOINT ["dotnet", "CffVaultManager.Web.dll"]
