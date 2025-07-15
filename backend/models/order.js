// Dummy order model (kan vervangen worden door echte DB)
module.exports = class Order {
  constructor(id, amount) {
    this.id = id;
    this.amount = amount;
  }
}
