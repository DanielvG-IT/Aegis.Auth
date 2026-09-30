using System.Collections;

using Microsoft.Extensions.DependencyInjection;

namespace Aegis.Auth.Plugins;

/// <summary>
/// Returned by <c>AddAegisAuth&lt;TContext&gt;()</c> to add plugins. It is also an
/// <see cref="IServiceCollection"/>, so code that chained service registrations onto
/// <c>AddAegisAuth</c> keeps compiling.
/// </summary>
public interface IAegisAuthBuilder : IServiceCollection
{
    IServiceCollection Services { get; }

    /// <summary>
    /// Registers a plugin and its services. Throws when the id is invalid or already registered,
    /// or when its error codes or rate-limit rules are invalid.
    /// </summary>
    IAegisAuthBuilder AddPlugin(AegisPlugin plugin);
}

internal sealed class AegisAuthBuilder(IServiceCollection services, AegisPluginRegistry registry) : IAegisAuthBuilder
{
    public IServiceCollection Services { get; } = services;

    public IAegisAuthBuilder AddPlugin(AegisPlugin plugin)
    {
        ArgumentNullException.ThrowIfNull(plugin);

        registry.Add(plugin);
        plugin.ConfigureServices(Services);
        return this;
    }

    public ServiceDescriptor this[int index] { get => Services[index]; set => Services[index] = value; }
    public int Count => Services.Count;
    public bool IsReadOnly => Services.IsReadOnly;
    public void Add(ServiceDescriptor item) => Services.Add(item);
    public void Clear() => Services.Clear();
    public bool Contains(ServiceDescriptor item) => Services.Contains(item);
    public void CopyTo(ServiceDescriptor[] array, int arrayIndex) => Services.CopyTo(array, arrayIndex);
    public IEnumerator<ServiceDescriptor> GetEnumerator() => Services.GetEnumerator();
    public int IndexOf(ServiceDescriptor item) => Services.IndexOf(item);
    public void Insert(int index, ServiceDescriptor item) => Services.Insert(index, item);
    public bool Remove(ServiceDescriptor item) => Services.Remove(item);
    public void RemoveAt(int index) => Services.RemoveAt(index);
    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}
