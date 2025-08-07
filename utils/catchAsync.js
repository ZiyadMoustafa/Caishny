// instead of using try and catch block all the time

module.exports = (fn) => (req, res, next) => {
  fn(req, res, next).catch(next);
};
