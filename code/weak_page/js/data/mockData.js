const photo = (id) => `https://images.unsplash.com/${id}?auto=format&fit=crop&w=900&q=82`;

export const categories = ["Tortas", "Pasteles", "Galletas", "Panadería"];

export const products = [
  { id: "tarta-frutos-rojos", name: "Tarta de frutos rojos", category: "Tortas", price: 28, description: "Base crujiente de almendra, crema de vainilla sedosa y una lluvia de frutos rojos frescos.", image: photo("photo-1464305795204-6f5bbfc7fb81"), stock: 8, featured: true, ingredients: ["Almendra", "harina", "vainilla", "frutos rojos", "nata"], allergens: ["Gluten", "frutos secos", "lácteos"] },
  { id: "cheesecake-vainilla", name: "Cheesecake de vainilla", category: "Pasteles", price: 32, description: "Cremoso cheesecake horneado lentamente con vainilla natural y base de galleta.", image: photo("photo-1533134242443-d4fd215305ad"), stock: 6, featured: true, ingredients: ["Queso crema", "vainilla", "huevo", "galleta"], allergens: ["Gluten", "huevo", "lácteos"] },
  { id: "croissant-mantequilla", name: "Croissant de mantequilla", category: "Panadería", price: 4.5, description: "Hojaldre artesanal de muchas capas, dorado por fuera y suave por dentro.", image: photo("photo-1555507036-ab1f4038808a"), stock: 18, featured: true, ingredients: ["Harina", "mantequilla", "leche", "levadura"], allergens: ["Gluten", "lácteos"] },
  { id: "cookies-chocolate", name: "Cookies de chocolate", category: "Galletas", price: 3.5, description: "Galletas tiernas con chocolate 70% y un delicado toque de sal marina.", image: photo("photo-1499636136210-6f4ee915583e"), stock: 24, featured: true, ingredients: ["Harina", "chocolate", "mantequilla", "azúcar", "huevo"], allergens: ["Gluten", "huevo", "lácteos"] },
  { id: "tarta-limon", name: "Tarta de limón", category: "Tortas", price: 26, description: "Crema cítrica de limón sobre masa sablé, terminada con merengue tostado.", image: photo("photo-1519915028121-7d3463d20b13"), stock: 7, featured: true, ingredients: ["Limón", "huevo", "harina", "mantequilla", "azúcar"], allergens: ["Gluten", "huevo", "lácteos"] },
  { id: "brownie-nuez", name: "Brownie de nuez", category: "Pasteles", price: 5.5, description: "Brownie intenso de chocolate belga y nueces, crujiente por fuera y fundente en el centro.", image: photo("photo-1606313564200-e75d5e30476c"), stock: 14, featured: false, ingredients: ["Chocolate", "nuez", "huevo", "mantequilla", "cacao"], allergens: ["Huevo", "lácteos", "frutos secos"] },
  { id: "macarons-surtidos", name: "Macarons surtidos", category: "Galletas", price: 18, description: "Caja de seis macarons delicados en sabores frambuesa, pistacho y chocolate.", image: photo("photo-1569864358642-9d1684040f43"), stock: 9, featured: true, ingredients: ["Almendra", "clara de huevo", "azúcar", "frambuesa"], allergens: ["Huevo", "frutos secos"] },
  { id: "roll-canela", name: "Roll de canela", category: "Panadería", price: 5, description: "Masa suave enrollada con canela de Ceilán y glaseado ligero de queso crema.", image: photo("photo-1509365465985-25d11c17e812"), stock: 12, featured: false, ingredients: ["Harina", "canela", "leche", "queso crema"], allergens: ["Gluten", "lácteos"] },
  { id: "tarta-chocolate", name: "Tarta de chocolate", category: "Tortas", price: 30, description: "Bizcocho húmedo de cacao, ganache brillante y virutas de chocolate artesanal.", image: photo("photo-1578985545062-69928b1d9587"), stock: 5, featured: true, ingredients: ["Cacao", "chocolate", "harina", "huevo", "nata"], allergens: ["Gluten", "huevo", "lácteos"] },
  { id: "madeleines", name: "Madeleines de miel", category: "Galletas", price: 9, description: "Pequeños bizcochos franceses con mantequilla avellanada y miel de flores.", image: photo("photo-1499636136210-6f4ee915583e"), stock: 15, featured: false, ingredients: ["Harina", "huevo", "mantequilla", "miel"], allergens: ["Gluten", "huevo", "lácteos"] },
  { id: "pan-brioche", name: "Brioche de la casa", category: "Panadería", price: 8, description: "Pan brioche dorado, enriquecido con mantequilla y preparado cada mañana.", image: photo("photo-1586444248902-2f64eddc13df"), stock: 10, featured: false, ingredients: ["Harina", "mantequilla", "huevo", "leche"], allergens: ["Gluten", "huevo", "lácteos"] },
  { id: "tarta-zanahoria", name: "Tarta de zanahoria", category: "Pasteles", price: 7, description: "Bizcocho especiado con zanahoria fresca, nueces y cobertura de queso crema.", image: photo("photo-1621303837174-89787a7d4729"), stock: 8, featured: false, ingredients: ["Zanahoria", "nuez", "canela", "harina", "queso crema"], allergens: ["Gluten", "frutos secos", "lácteos"] }
];

export const users = [
  { id: "user-ana", name: "Ana Martínez", email: "ana@dulcenube.com", password: "ana123", phone: "555 234 6789" },
  { id: "user-demo", name: "Cliente Dulce Nube", email: "hola@dulcenube.com", password: "nube123", phone: "555 123 4567" }
];

export const testimonials = [
  { name: "María G.", text: "La tarta de frutos rojos fue el centro de nuestra celebración. Preciosa y deliciosa.", rating: 5, date: "Hace 2 semanas" },
  { name: "Lucía R.", text: "Se nota el cariño en cada detalle. Los croissants son mis favoritos del domingo.", rating: 5, date: "Hace 1 mes" },
  { name: "Diego P.", text: "Encargamos el cheesecake para un cumpleaños y todos repitieron. ¡Volveremos!", rating: 5, date: "Hace 3 semanas" }
];

export const initialOrders = [];
export const initialContactMessages = [];
