FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /app

COPY . ./
RUN dotnet publish -c Release -o out

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS runtime
WORKDIR /app
COPY --from=build /app/out .
COPY ./Covenant/Data ./Data
EXPOSE 7443 80 443
ENTRYPOINT ["dotnet", "Covenant.dll"]
