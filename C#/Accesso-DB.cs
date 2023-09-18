using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;

// Definizione di una classe per il modello di utente
public class User
{
    public int Id { get; set; }
    public string Email { get; set; }
    public string PasswordHash { get; set; }
    public string Salt { get; set; }
}

// Definizione di un contesto del database
public class AppDbContext : DbContext
{
    public DbSet<User> Users { get; set; }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        optionsBuilder.UseSqlServer("connection_string_here"); // Sostituire con la tua stringa di connessione al database
    }
}

class Program
{
    static void Main()
    {
        using (var context = new AppDbContext())
        {
            // Creazione del database se non esiste
            context.Database.EnsureCreated();

            // Registrazione di un nuovo utente
            var email = "user@example.com";
            var password = "password123";
            RegisterUser(context, email, password);

            // Autenticazione di un utente
            var isAuthenticated = AuthenticateUser(context, email, password);
            Console.WriteLine($"L'utente è autenticato: {isAuthenticated}");
        }
    }

    static void RegisterUser(AppDbContext context, string email, string password)
    {
        // Generazione di un salt casuale
        var saltBytes = new byte[32];
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(saltBytes);
        }
        var salt = Convert.ToBase64String(saltBytes);

        // Calcolo dell'hash della password con il salt
        var passwordWithSalt = password + salt;
        var passwordHashBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(passwordWithSalt));
        var passwordHash = Convert.ToBase64String(passwordHashBytes);

        // Creazione di un nuovo utente
        var user = new User
        {
            Email = email,
            PasswordHash = passwordHash,
            Salt = salt
        };

        // Aggiunta dell'utente al database
        context.Users.Add(user);
        context.SaveChanges();
    }

    static bool AuthenticateUser(AppDbContext context, string email, string password)
    {
        var user = context.Users.SingleOrDefault(u => u.Email == email);
        if (user == null)
        {
            return false; // Utente non trovato
        }

        // Calcolo dell'hash della password inserita con il salt
        var passwordWithSalt = password + user.Salt;
        var passwordHashBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(passwordWithSalt));
        var passwordHash = Convert.ToBase64String(passwordHashBytes);

        // Confronto dell'hash calcolato con l'hash memorizzato nel database
        return user.PasswordHash == passwordHash;
    }
}
