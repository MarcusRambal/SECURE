export const formatPrice = amount => new Intl.NumberFormat("es-MX", { style: "currency", currency: "MXN" }).format(amount);
export const formatDate = value => new Intl.DateTimeFormat("es-MX", { dateStyle: "long" }).format(new Date(value));
